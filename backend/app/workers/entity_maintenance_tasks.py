"""Entity-maintenance tasks that call an AI provider (run on the ai worker).

Four task families share this module — the same AI invocation pattern and
the same maintenance log (``entity_maintenance_log``):

  actor_profile_refresh        — weekly: pick the most-active actors whose
                                  profile description hasn't been touched
                                  recently and have the model refresh it
                                  from recent entries (gated by
                                  ``entity_maintenance_mode``, shadow/apply).
  assessment backfill          — daily: draft the AI description paragraph
                                  for entities that have none.
  entity_name_normalization    — on demand: canonical-name proposals.
  ai_enrich_gap_batch          — on demand: fill empty profile fields.

  merge review                 — daily: put likely-duplicate pairs of
                                  existing actors, malware and tools in
                                  front of the model; "same" verdicts become
                                  Merge proposals on the Review tab
                                  (``services/entity_merge_review.py``).

An entity minted by one article is judged against the catalogue at creation
by the adjudicate stage (``services/entry_adjudication.py``); the merge
review is for pairs that both already exist.

All of them run on the dedicated `celery-worker-ai` service (the serialized
"ai" queue) so AI calls hit the provider one at a time.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.caller import Caller
from app.ai.engine import run_task
from app.config import settings
from app.core.metrics import CELERY_TASK_DURATION_SECONDS, CELERY_TASKS_TOTAL
from app.models.ai_result import AIResult
from app.models.entity_maintenance import ActorDescriptionHistory, EntityMaintenanceLog
from app.models.entry import Entry
from app.models.malware_family import EntryMalware, MalwareFamily
from app.models.product import EntryProduct, Product
from app.models.threat_actor import EntryThreatActor, ThreatActor
from app.models.tool import EntryTool, Tool
from app.models.vendor import EntryVendor, Vendor
from app.workers.celery_app import celery_app
from app.workers.db import run_async, worker_session

# Mirror of ENTITY_TYPE_REGISTRY in api/entity_merge.py — duplicated here to
# avoid the worker depending on the API layer (which would pull in FastAPI).
_WORKER_ENTITY_TYPES: dict[str, dict] = {
    "threat_actor": {
        "model": ThreatActor,
        "junction_model": EntryThreatActor,
        "junction_fk": "threat_actor_id",
        "table": "threat_actors",
    },
    "malware": {
        "model": MalwareFamily,
        "junction_model": EntryMalware,
        "junction_fk": "malware_family_id",
        "table": "malware_families",
    },
    "vendor": {
        "model": Vendor,
        "junction_model": EntryVendor,
        "junction_fk": "vendor_id",
        "table": "vendors",
    },
    "product": {
        "model": Product,
        "junction_model": EntryProduct,
        "junction_fk": "product_id",
        "table": "products",
    },
    "tool": {
        "model": Tool,
        "junction_model": EntryTool,
        "junction_fk": "tool_id",
        "table": "tools",
    },
}

logger = logging.getLogger(__name__)


# ============================================================
# Shared helpers
# ============================================================


def _current_mode() -> str:
    """Actor profile refresh mode: 'shadow' logs the rewritten description as a
    proposal; 'apply' writes it (with ActorDescriptionHistory as the undo)."""
    raw = (settings.get("entity_maintenance_mode") or "shadow").lower()
    if raw not in ("shadow", "apply"):
        logger.warning("Unknown entity_maintenance_mode=%r; defaulting to shadow", raw)
        return "shadow"
    return raw


async def _resolve_system_user(db: AsyncSession) -> uuid.UUID | None:
    from app.services.system_user import get_system_user_id

    return await get_system_user_id(db)


# ============================================================
# Entity-merge maintenance — kickoff + per-cluster
# ============================================================


# ============================================================
# Actor profile refresh — kickoff + per-actor
# ============================================================


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.kickoff_actor_profile_refresh",
    soft_time_limit=120,
    time_limit=180,
)
def kickoff_actor_profile_refresh() -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_refresh_async())
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_actor_profile_refresh", status="success").inc()
        logger.info("kickoff_actor_profile_refresh: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_actor_profile_refresh", status="error").inc()
        logger.exception("kickoff_actor_profile_refresh failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="kickoff_actor_profile_refresh").observe(time.monotonic() - start)


async def _kickoff_refresh_async() -> dict:
    """Pick top-N active actors not refreshed recently; enqueue per-actor tasks."""
    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        # Knobs are read after the warm — see _kickoff_merge_async.
        top_n = int(settings.get("actor_refresh_top_n_per_run") or 20)
        min_days_since_refresh = int(settings.get("actor_refresh_min_age_days") or 60)
        activity_window_days = int(settings.get("actor_refresh_activity_window_days") or 90)

        # Most-active in activity window = highest count of recent entry junctions.
        cutoff = datetime.now(UTC) - timedelta(days=activity_window_days)
        # Most-recently-refreshed actors (via history) get a min-age guard.
        refresh_cutoff = datetime.now(UTC) - timedelta(days=min_days_since_refresh)

        recently_refreshed_q = await db.execute(
            select(ActorDescriptionHistory.actor_id)
            .where(ActorDescriptionHistory.created_at >= refresh_cutoff)
            .distinct()
        )
        recently_refreshed = {r for r in recently_refreshed_q.scalars().all()}

        activity_q = await db.execute(
            select(
                ThreatActor.id,
                func.count(EntryThreatActor.entry_id).label("hits"),
            )
            .join(EntryThreatActor, EntryThreatActor.threat_actor_id == ThreatActor.id)
            .join(Entry, Entry.id == EntryThreatActor.entry_id)
            .where(Entry.published_at >= cutoff)
            .group_by(ThreatActor.id)
            .order_by(func.count(EntryThreatActor.entry_id).desc())
            .limit(top_n * 4)  # over-fetch so we can filter and still hit top_n
        )
        picked: list[uuid.UUID] = []
        for actor_id, _hits in activity_q.all():
            if actor_id in recently_refreshed:
                continue
            picked.append(actor_id)
            if len(picked) >= top_n:
                break

    for actor_id in picked:
        refresh_actor_profile.apply_async(args=[str(actor_id)], queue="ai")

    return {"refreshed_enqueued": len(picked), "skipped_recent_refresh": len(recently_refreshed)}


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.refresh_actor_profile",
    bind=True,
    soft_time_limit=300,
    time_limit=360,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def refresh_actor_profile(self, actor_id: str) -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_refresh_actor_async(uuid.UUID(actor_id)))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="refresh_actor_profile", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(
            task_name="refresh_actor_profile",
            status="success" if status in {"updated", "shadow_updated", "no_change", "missing"} else "error",
        ).inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_actor_profile", status="error").inc()
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="refresh_actor_profile", status="error").inc()
        logger.exception("refresh_actor_profile failed for %s", actor_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="refresh_actor_profile").observe(time.monotonic() - start)


async def _refresh_actor_async(actor_id: uuid.UUID) -> dict:
    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        # Knobs are read after the warm — see _kickoff_merge_async.
        activity_window_days = int(settings.get("actor_refresh_activity_window_days") or 90)
        sample_n = int(settings.get("actor_refresh_sample_n") or 20)

        mode = _current_mode()
        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            return {"status": "no_admin_user"}

        actor = (await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))).scalar_one_or_none()
        if not actor:
            return {"status": "missing", "actor_id": str(actor_id)}

        cutoff = datetime.now(UTC) - timedelta(days=activity_window_days)
        recent_q = await db.execute(
            select(Entry.title, Entry.summary, Entry.published_at)
            .join(EntryThreatActor, EntryThreatActor.entry_id == Entry.id)
            .where(
                and_(
                    EntryThreatActor.threat_actor_id == actor.id,
                    Entry.published_at >= cutoff,
                )
            )
            .order_by(Entry.published_at.desc().nullslast())
            .limit(sample_n)
        )
        recent_rendered = "\n\n".join(
            f"- ({(p.isoformat() if p else 'undated')}) {t or '(no title)'}\n  {(s or '')[:400]}"
            for t, s, p in recent_q.all()
        )
        if not recent_rendered:
            return {"status": "no_recent_activity", "actor_id": str(actor_id)}

        variables = {
            "actor_id": str(actor.id),
            "actor_name": actor.name,
            "actor_aliases": ", ".join(actor.aliases or []) or "(none)",
            "current_description": actor.description or "",
            "recent_entries": recent_rendered,
            "mode": mode,
        }

        try:
            result = await run_task(
                db=db,
                user_id=system_user_id,
                task_name="actor_profile_refresh",
                variables=variables,
                target_type="threat_actor",
                target_id=actor.id,
                force=True,
                caller=Caller.system(system_user_id),
            )
        except Exception as e:
            logger.exception("actor_profile_refresh run_task failed: %s", e)
            return {"status": "ai_error", "error": str(e)}

        if result and result.get("_extraction_status") == "provider_paused":
            return {
                "status": "provider_paused",
                "pause_until": result.get("_pause_until"),
            }

        if not result or result.get("_extraction_status") != "success":
            return {"status": "ai_no_success", "ai_status": (result or {}).get("_extraction_status")}

        ai_result_q = await db.execute(
            select(AIResult.id)
            .join(AIResult.task)
            .where(
                AIResult.target_type == "threat_actor",
                AIResult.target_id == actor.id,
                AIResult.is_current.is_(True),
            )
            .order_by(AIResult.created_at.desc())
            .limit(1)
        )
        ai_result_id = ai_result_q.scalar_one_or_none()

        action = result.get("action")
        if action == "no_change":
            db.add(
                ActorDescriptionHistory(
                    actor_id=actor.id,
                    previous_text=actor.description,
                    new_text=actor.description,
                    change_reason=(result.get("reason") or "no material change")[:2000],
                    source="ai_refresh",
                    ai_result_id=ai_result_id,
                    applied=False,
                )
            )
            await db.commit()
            return {"status": "no_change", "actor_id": str(actor.id)}

        if action != "update":
            await db.commit()
            return {"status": "ai_bad_action", "action": action}

        new_description = result.get("new_description")
        change_summary = result.get("change_summary") or ""
        if not new_description:
            await db.commit()
            return {"status": "ai_missing_description", "actor_id": str(actor.id)}

        previous = actor.description
        history_row = ActorDescriptionHistory(
            actor_id=actor.id,
            previous_text=previous,
            new_text=new_description,
            change_reason=change_summary[:2000],
            source="ai_refresh",
            ai_result_id=ai_result_id,
            applied=(mode == "apply"),
        )
        db.add(history_row)

        if mode == "apply":
            actor.description = new_description
            await db.commit()
            return {"status": "updated", "actor_id": str(actor.id)}

        await db.commit()
        return {"status": "shadow_updated", "actor_id": str(actor.id)}


# ============================================================
# Assessment backfill (fill empty descriptions from linked reporting)
# ============================================================
#
# `kickoff_assessment_backfill` finds entities of every profile type that have
# linked reporting but no description/assessment yet, and dispatches one
# `backfill_entity_assessment` per entity on the ai queue. Each task
# runs the same `article_summary` path as the profile "AI refresh" button
# (app/services/entity_summary.py), so results are identical to a manual
# click. Only ever fills empty descriptions — it never overwrites analyst or
# prior AI text; the weekly actor_profile_refresh above owns keeping active
# actors current.

# CVE descriptions belong to NVD, not to us. Two reasons this job stays out:
# the NVD text is authoritative where an AI paraphrase of press coverage is
# not, and `run_cve_nvd_backfill` selects on `description IS NULL` — writing
# anything here drops the CVE out of that sweep permanently, leaving it with
# no CVSS score, severity, affected products, references, or nvd_data either.
# A CVE only reaches this job because NVD already failed on it (reserved,
# rejected, unpublished, or a hallucinated ID), which is exactly when invented
# prose is least welcome. The profile's manual AI-refresh button is unaffected.
# cve: assessments come from NVD data, not prose. observable: an AI-drafted
# "dossier" for an IP address is v1's junk-prose problem reborn — the ledger's
# description stays analyst-written or empty.
ASSESSMENT_BACKFILL_EXCLUDED_TYPES = frozenset({"cve", "observable"})


async def find_assessment_backfill_candidates(
    db: AsyncSession, batch_size: int, min_articles: int, retry_days: int = 7
) -> list[tuple[str, uuid.UUID, int]]:
    """(entity_type, entity_id, article_count) for entities with linked
    reporting but an empty description, best-covered entities first.

    Entities attempted within `retry_days` are skipped. Ordering is by article
    count descending against a fixed per-run budget, so without that window the
    same highest-count entities are re-picked every run — a handful of entities
    the AI reliably fails on would hold the top slots forever and the rest of
    the queue would never be reached.
    """
    from app.models.ai_task import AITask
    from app.services.entity_summary import ENTITY_MODEL_MAP

    # Attempts are recorded by run_task as AIResult rows keyed to the entity
    # (see generate_entity_assessment), so the cooldown needs no state of its own.
    task_id = (
        await db.execute(select(AITask.id).where(AITask.name == "article_summary").limit(1))
    ).scalar_one_or_none()
    cutoff = datetime.now(UTC) - timedelta(days=retry_days)

    candidates: list[tuple[str, uuid.UUID, int]] = []
    for etype, (model_cls, junction_cls, fk_attr) in ENTITY_MODEL_MAP.items():
        if etype in ASSESSMENT_BACKFILL_EXCLUDED_TYPES:
            continue
        desc_col = getattr(model_cls, "description", None)
        if desc_col is None:
            desc_col = getattr(model_cls, "context", None)
        if desc_col is None:
            continue
        fk_col = getattr(junction_cls, fk_attr)
        q = (
            select(model_cls.id, func.count(fk_col).label("hits"))
            .join(junction_cls, fk_col == model_cls.id)
            .where(or_(desc_col.is_(None), func.trim(desc_col) == ""))
            .group_by(model_cls.id)
            .having(func.count(fk_col) >= min_articles)
            .order_by(func.count(fk_col).desc())
            .limit(batch_size)
        )
        if task_id is not None:
            recent_attempt = (
                select(AIResult.id)
                .where(
                    AIResult.task_id == task_id,
                    AIResult.target_type == etype,
                    AIResult.target_id == model_cls.id,
                    AIResult.created_at >= cutoff,
                )
                .exists()
            )
            q = q.where(~recent_attempt)
        rows = await db.execute(q)
        candidates.extend((etype, eid, int(hits)) for eid, hits in rows.all())

    candidates.sort(key=lambda c: c[2], reverse=True)
    return candidates[:batch_size]


async def find_assessment_refresh_candidates(
    db: AsyncSession, batch_size: int, min_new_articles: int, retry_days: int = 7
) -> list[tuple[str, uuid.UUID, int]]:
    """(entity_type, entity_id, new_article_count) for assessments that have gone stale.

    The backfill above only ever picks entities whose description is *empty*, so
    an entity assessed once is never revisited — a paragraph written in June
    still describes June no matter what has been reported since.

    Staleness is measured against the assessment's own input window: the writer
    reads the N most recent linked articles, so once that many new articles have
    been linked since the paragraph was written, most of what it was built from
    is no longer what it would be built from today.

    Two guards keep this from clobbering anything a person or an enrichment
    source wrote:

    - the entity must have a *successful* article_summary AIResult, i.e. the
      current text came from this writer and not from an analyst or a feed;
    - the ordinary retry cooldown still applies, so a refresh that fails does
      not re-enter the queue tomorrow.
    """
    from app.models.ai_result import AIResult
    from app.models.ai_task import AITask
    from app.services.entity_summary import ENTITY_MODEL_MAP

    task_id = (
        await db.execute(select(AITask.id).where(AITask.name == "article_summary").limit(1))
    ).scalar_one_or_none()
    if task_id is None:
        return []

    cutoff = datetime.now(UTC) - timedelta(days=retry_days)
    candidates: list[tuple[str, uuid.UUID, int]] = []

    for etype, (model_cls, junction_cls, fk_attr) in ENTITY_MODEL_MAP.items():
        if etype in ASSESSMENT_BACKFILL_EXCLUDED_TYPES:
            continue
        desc_col = getattr(model_cls, "description", None)
        if desc_col is None:
            desc_col = getattr(model_cls, "context", None)
        if desc_col is None:
            continue
        fk_col = getattr(junction_cls, fk_attr)

        # When each entity's assessment was last written. A row whose parsed
        # result carries no "summary" key is a failed attempt (parse_error,
        # provider pause) — those are recorded deliberately for the cooldown,
        # and must not count as the description's author.
        assessed = (
            select(
                AIResult.target_id.label("entity_id"),
                func.max(AIResult.created_at).label("assessed_at"),
            )
            .where(
                AIResult.task_id == task_id,
                AIResult.target_type == etype,
                AIResult.parsed_result.has_key("summary"),  # noqa: W601 — JSONB ?, not dict.has_key
            )
            .group_by(AIResult.target_id)
            .subquery()
        )

        fresh = func.count(junction_cls.entry_id)
        q = (
            select(model_cls.id, fresh)
            .join(assessed, assessed.c.entity_id == model_cls.id)
            .join(junction_cls, fk_col == model_cls.id)
            .where(
                desc_col.is_not(None),
                func.trim(desc_col) != "",
                junction_cls.extracted_at > assessed.c.assessed_at,
                # Same cooldown as the backfill: any attempt inside the window
                # (success or failure) takes the entity out of the running.
                ~(
                    select(AIResult.id)
                    .where(
                        AIResult.task_id == task_id,
                        AIResult.target_type == etype,
                        AIResult.target_id == model_cls.id,
                        AIResult.created_at >= cutoff,
                    )
                    .exists()
                ),
            )
            .group_by(model_cls.id)
            .having(fresh >= min_new_articles)
            .order_by(fresh.desc())
            .limit(batch_size)
        )
        rows = await db.execute(q)
        candidates.extend((etype, eid, int(n)) for eid, n in rows.all())

    candidates.sort(key=lambda c: c[2], reverse=True)
    return candidates[:batch_size]


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.kickoff_assessment_backfill",
    bind=True,
    soft_time_limit=180,
    time_limit=240,
)
def kickoff_assessment_backfill(self) -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_assessment_backfill_async())
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_assessment_backfill", status="success").inc()
        logger.info("kickoff_assessment_backfill: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_assessment_backfill", status="error").inc()
        logger.exception("kickoff_assessment_backfill failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="kickoff_assessment_backfill").observe(time.monotonic() - start)


async def _kickoff_assessment_backfill_async() -> dict:
    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        # Defaults live on Settings (app/config.py) and are overridable from
        # Settings > System; `or` fallbacks would silently swallow a deliberate 0.
        batch_size = int(settings.get("assessment_backfill_batch_size"))
        min_articles = int(settings.get("assessment_backfill_min_articles"))
        retry_days = int(settings.get("assessment_backfill_retry_days"))
        candidates = await find_assessment_backfill_candidates(db, batch_size, min_articles, retry_days)

        # Stale refreshes are a separate budget from the empty-description
        # backfill: they must never crowd out an entity that has no assessment
        # at all, so they get their own (smaller) batch rather than sharing one.
        refreshes: list[tuple[str, uuid.UUID, int]] = []
        if settings.get("assessment_refresh_enabled"):
            already = {(etype, eid) for etype, eid, _ in candidates}
            refreshes = [
                c
                for c in await find_assessment_refresh_candidates(
                    db,
                    int(settings.get("assessment_refresh_batch_size")),
                    int(settings.get("assessment_refresh_min_new_articles")),
                    retry_days,
                )
                if (c[0], c[1]) not in already
            ]

    for etype, entity_id, _hits in candidates:
        backfill_entity_assessment.apply_async(args=[etype, str(entity_id)], queue="ai")
    for etype, entity_id, _new in refreshes:
        backfill_entity_assessment.apply_async(args=[etype, str(entity_id)], kwargs={"refresh": True}, queue="ai")

    by_type: dict[str, int] = defaultdict(int)
    for etype, _eid, _hits in candidates:
        by_type[etype] += 1
    refresh_by_type: dict[str, int] = defaultdict(int)
    for etype, _eid, _new in refreshes:
        refresh_by_type[etype] += 1
    return {
        "enqueued": len(candidates),
        "by_type": dict(by_type),
        "refreshed": len(refreshes),
        "refresh_by_type": dict(refresh_by_type),
        "batch_size": batch_size,
        "min_articles": min_articles,
        "retry_days": retry_days,
    }


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.backfill_entity_assessment",
    bind=True,
    soft_time_limit=300,
    time_limit=360,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def backfill_entity_assessment(self, entity_type: str, entity_id: str, refresh: bool = False) -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_backfill_assessment_async(entity_type, uuid.UUID(entity_id), refresh=refresh))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="backfill_entity_assessment", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        ok = status in {"updated", "already_has_assessment", "not_found"}
        CELERY_TASKS_TOTAL.labels(
            task_name="backfill_entity_assessment",
            status="success" if ok else "error",
        ).inc()
        if ok:
            logger.info("backfill_entity_assessment %s %s: %s", entity_type, entity_id, status)
        else:
            # no_ai / ai_error / no_admin_user / unsupported_type all return
            # normally, so without this the only trace of a failure is a
            # Prometheus counter with no entity attached.
            logger.warning(
                "backfill_entity_assessment %s %s produced no assessment: %s",
                entity_type,
                entity_id,
                stats,
            )
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entity_assessment", status="error").inc()
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="backfill_entity_assessment", status="error").inc()
        logger.exception("backfill_entity_assessment failed for %s %s", entity_type, entity_id)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="backfill_entity_assessment").observe(time.monotonic() - start)


async def _backfill_assessment_async(entity_type: str, entity_id: uuid.UUID, refresh: bool = False) -> dict:
    from app.services.entity_summary import generate_entity_assessment

    async with worker_session() as db:
        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            return {"status": "no_admin_user"}
        # only_if_empty re-checks at run time so an analyst (or another job)
        # writing a description between kickoff and execution is never clobbered.
        # A refresh is the deliberate exception: the candidate query already
        # established that the text there is this writer's own, now stale.
        return await generate_entity_assessment(
            db, system_user_id, entity_type, entity_id, only_if_empty=not refresh, caller=Caller.system(system_user_id)
        )


# ============================================================
# Entity name normalization (AI-driven per-name correctness check)
# ============================================================
#
# `kickoff_name_normalization_ai` walks the five entity tables, batches names
# into groups of ~30, and dispatches one `process_name_normalization_batch`
# per group on the ai queue. Each batch task asks Claude to judge
# every name in the batch and emit `keep` or `rename` decisions; rename
# decisions become `normalize_name` proposals in EntityMaintenanceLog.
#
# Pure renames only — alias collisions / merge candidates belong to the
# merge_engine flow, not here.


_NAME_NORMALIZATION_BATCH_SIZE = 30


def _entity_snapshot_for_normalize_worker(entity, entity_type: str) -> dict:
    return {
        "id": str(entity.id),
        "name": getattr(entity, "name", None),
        "entity_type": entity_type,
        "aliases": list(getattr(entity, "aliases", None) or []),
        "article_count": getattr(entity, "article_count", 0),
    }


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.kickoff_name_normalization_ai",
    bind=True,
    soft_time_limit=180,
    time_limit=240,
)
def kickoff_name_normalization_ai(self, entity_type: str | None = None) -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_kickoff_name_normalization_async(entity_type))
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_name_normalization_ai", status="success").inc()
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="kickoff_name_normalization_ai", status="error").inc()
        logger.exception("kickoff_name_normalization_ai failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="kickoff_name_normalization_ai").observe(time.monotonic() - start)


async def _kickoff_name_normalization_async(entity_type: str | None) -> dict:
    types_to_scan = [entity_type] if entity_type else list(_WORKER_ENTITY_TYPES.keys())
    batches_dispatched = 0
    total_entities = 0

    async with worker_session() as db:
        for etype in types_to_scan:
            spec = _WORKER_ENTITY_TYPES.get(etype)
            if not spec:
                continue
            model = spec["model"]
            rows = (await db.execute(select(model.id, model.name).order_by(model.name))).all()
            ids = [(str(r[0]), r[1]) for r in rows if r[1]]
            total_entities += len(ids)

            for i in range(0, len(ids), _NAME_NORMALIZATION_BATCH_SIZE):
                batch = ids[i : i + _NAME_NORMALIZATION_BATCH_SIZE]
                payload = [{"id": eid, "name": name} for eid, name in batch]
                process_name_normalization_batch.apply_async(args=[etype, payload], queue="ai")
                batches_dispatched += 1

    return {
        "status": "dispatched",
        "batches": batches_dispatched,
        "entities": total_entities,
        "batch_size": _NAME_NORMALIZATION_BATCH_SIZE,
    }


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.process_name_normalization_batch",
    bind=True,
    soft_time_limit=240,
    time_limit=300,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def process_name_normalization_batch(self, entity_type: str, batch: list[dict]) -> dict:
    start = time.monotonic()
    try:
        stats = run_async(_process_name_normalization_batch_async(entity_type, batch))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="process_name_normalization_batch", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(task_name="process_name_normalization_batch", status="success").inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="process_name_normalization_batch", status="error").inc()
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="process_name_normalization_batch", status="error").inc()
        logger.exception("process_name_normalization_batch failed for %s", entity_type)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="process_name_normalization_batch").observe(
            time.monotonic() - start
        )


async def _process_name_normalization_batch_async(entity_type: str, batch: list[dict]) -> dict:
    spec = _WORKER_ENTITY_TYPES.get(entity_type)
    if not spec or not batch:
        return {"status": "skipped", "entities": 0}

    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            return {"status": "no_admin_user"}

        # Build the entities_block string the AI sees. Keep it compact —
        # the AI is judging cosmetic correctness, not semantic context.
        entities_block = "\n".join(f"- entity_id={item['id']}  name={json.dumps(item['name'])}" for item in batch)

        variables = {
            "entity_type": entity_type,
            "entities_block": entities_block,
        }

        # Use a synthetic target_id so the engine's dedup doesn't accidentally
        # cache across batches with different contents.
        synthetic_target = uuid.uuid4()
        try:
            result = await run_task(
                db=db,
                user_id=system_user_id,
                task_name="entity_name_normalization",
                variables=variables,
                target_type="name_normalization_batch",
                target_id=synthetic_target,
                force=True,
                caller=Caller.system(system_user_id),
            )
        except Exception as e:  # provider quota / transient
            from app.ai.providers.claude_code_provider import QuotaExhaustedError

            if isinstance(e, QuotaExhaustedError):
                return {
                    "status": "provider_paused",
                    "pause_until": e.pause_until.isoformat() if getattr(e, "pause_until", None) else None,
                }
            raise

        if not result:
            return {"status": "no_assignment"}

        decisions = result.get("decisions") or []
        renames = 0
        skipped = 0
        valid_ids = {item["id"] for item in batch}
        by_id = {item["id"]: item["name"] for item in batch}

        model = spec["model"]

        for d in decisions:
            if not isinstance(d, dict):
                continue
            eid_str = str(d.get("entity_id") or "")
            action = d.get("action")
            if eid_str not in valid_ids or action != "rename":
                continue
            proposed = (d.get("proposed_name") or "").strip()
            current = by_id.get(eid_str, "")
            if not proposed or proposed == current:
                continue

            try:
                eid = uuid.UUID(eid_str)
            except ValueError:
                continue

            # Re-fetch the entity inside this txn so the snapshot is current.
            entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
            if not entity:
                skipped += 1
                continue

            # If another entity in the same table already owns the proposed
            # name (case-insensitive), skip — that's a merge job.
            collision = (
                await db.execute(
                    select(model.id).where(func.lower(model.name) == proposed.lower(), model.id != entity.id)
                )
            ).scalar_one_or_none()
            if collision is not None:
                skipped += 1
                continue

            db.add(
                EntityMaintenanceLog(
                    entity_type=entity_type,
                    entity_id=entity.id,
                    action="normalize_name",
                    mode="shadow",
                    before={"entity": _entity_snapshot_for_normalize_worker(entity, entity_type)},
                    after={
                        "kind": "rename",
                        "proposed_name": proposed,
                        "merge_target_id": None,
                    },
                    reasoning=("AI: " + (d.get("reason") or "name needs normalization"))[:500],
                    applied=False,
                )
            )
            renames += 1

        await db.commit()
        return {
            "status": "processed",
            "entity_type": entity_type,
            "batch_size": len(batch),
            "renames_proposed": renames,
            "skipped": skipped,
        }


# ───────────────────────────────────────────────────────────────────
# AI gap research — Claude Code with web search fills missing entity fields.
# Triggered by the Entity Hygiene → "Enrich N" buttons via the
# /admin/hygiene/enrichment-gaps/enrich endpoint.
# ───────────────────────────────────────────────────────────────────

# Per-(entity_type, field) prompt guidance Claude sees in the system message.
# Each entry tells the model what format to return and where to look.
_GAP_FIELD_GUIDANCE: dict[tuple[str, str], str] = {
    ("threat_actor", "description"): (
        "Write a 1-3 sentence factual description of this threat actor: who attributes them, "
        "what they target, what their TTPs are at a high level. Neutral catalog tone — no breathless "
        "language. Cite vendor reports or MITRE ATT&CK group pages. If the actor is ambiguous or "
        "you cannot find authoritative coverage, return `unknown`."
    ),
    ("threat_actor", "mitre_id"): (
        "Return the MITRE ATT&CK group ID like `G0007` (APT28) or `G0050` (APT32). Check "
        "https://attack.mitre.org/groups/ and search for the group name and known aliases. "
        "Return `unknown` if no ATT&CK group page exists for this actor."
    ),
    ("threat_actor", "country"): (
        "Return the country of origin (or primary state sponsor) in English (e.g., `Russia`, "
        "`North Korea`, `China`, `Iran`, `United States`). Use the conventional country name "
        "as it appears on Wikipedia. If attribution is disputed or unknown, return `unknown`."
    ),
    ("threat_actor", "motivation"): (
        "One of: `financial`, `espionage`, `hacktivism`, `disruption`, `sabotage`, "
        "`terrorism`, `unknown`. Comma-separate for combined motivations (e.g., "
        "`espionage,financial`). Pick the dominant motive(s) based on victimology and TTPs."
    ),
    ("malware", "description"): (
        "Write a 1-3 sentence factual description: what this malware does, what platform it targets, "
        "what it is best known for. Cite vendor research or MITRE ATT&CK software pages. "
        "Return `unknown` if no authoritative coverage exists."
    ),
    ("malware", "malware_type"): (
        "One lowercase keyword from: `ransomware`, `infostealer`, `rat`, `loader`, `dropper`, "
        "`downloader`, `framework`, `implant`, `keylogger`, `miner`, `rootkit`, `spyware`, "
        "`trojan`, `webshell`, `wiper`, `worm`, `other`. Pick the most specific that fits."
    ),
    ("product", "vendor_id"): (
        "Return the vendor company name that publishes / owns this product (e.g., `Microsoft`, "
        "`Cisco`, `Palo Alto Networks`, `Atlassian`, `Apache Software Foundation`). Use the "
        "canonical company name. Return `unknown` if you cannot identify the owner."
    ),
    ("cve", "cvss"): (
        "Return the CVSS v3.x base score as a decimal between 0.0 and 10.0 (e.g., `7.5`, `9.8`). "
        "Use NVD (https://nvd.nist.gov/vuln/detail/<CVE>) as the authoritative source; vendor "
        "advisories as fallback. If only CVSS v2 is available, return `unknown` rather than guess."
    ),
}

_AI_ENRICH_BATCH_SIZE = 10


def _resolve_fk_by_name(db_data: list[dict], name_value: str) -> uuid.UUID | None:
    """Look up an entity's UUID by case-insensitive name or alias match.

    `db_data` is a pre-loaded list of {id, name, aliases} dicts (countries,
    vendors, etc.). Returns None if no match — caller decides whether to
    skip the writeback or create a new row (we currently skip)."""
    needle = name_value.strip().lower()
    for row in db_data:
        if (row["name"] or "").lower() == needle:
            return row["id"]
        for alias in row.get("aliases") or []:
            if (alias or "").lower() == needle:
                return row["id"]
    return None


@celery_app.task(
    name="app.workers.entity_maintenance_tasks.ai_enrich_gap_batch",
    bind=True,
    soft_time_limit=900,
    time_limit=960,
    autoretry_for=(TimeoutError,),
    max_retries=2,
)
def ai_enrich_gap_batch(self, entity_type: str, field: str, batch: list[dict]) -> dict:
    """Research a batch of entities with Claude Code + web search and write
    high-confidence values back into the matching entity column.

    `batch` is `[{"id": "<uuid>", "name": "<entity name>"}]`, capped at
    `_AI_ENRICH_BATCH_SIZE` by the dispatcher. Routed to the ai queue
    via the celery_app task_routes table.
    """
    start = time.monotonic()
    try:
        stats = run_async(_ai_enrich_gap_batch_async(entity_type, field, batch))
        status = stats.get("status", "unknown")
        if status == "provider_paused":
            pause_until_str = stats.get("pause_until")
            countdown = 3600
            if pause_until_str:
                try:
                    pause_until = datetime.fromisoformat(pause_until_str)
                    countdown = max(60, min(3600, int((pause_until - datetime.now(UTC)).total_seconds()) + 30))
                except ValueError:
                    pass
            CELERY_TASKS_TOTAL.labels(task_name="ai_enrich_gap_batch", status="provider_paused").inc()
            raise self.retry(countdown=countdown, max_retries=24)
        CELERY_TASKS_TOTAL.labels(task_name="ai_enrich_gap_batch", status="success").inc()
        return stats
    except self.MaxRetriesExceededError:
        CELERY_TASKS_TOTAL.labels(task_name="ai_enrich_gap_batch", status="error").inc()
        raise
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="ai_enrich_gap_batch", status="error").inc()
        logger.exception("ai_enrich_gap_batch failed for %s/%s", entity_type, field)
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="ai_enrich_gap_batch").observe(time.monotonic() - start)


async def _ai_enrich_gap_batch_async(entity_type: str, field: str, batch: list[dict]) -> dict:
    spec = _WORKER_ENTITY_TYPES.get(entity_type)
    # cve isn't in _WORKER_ENTITY_TYPES (it's not a "maintainable" entity in the
    # merge/normalize sense) — handle it via a direct model lookup below.
    if entity_type == "cve":
        from app.models.cve import CVE

        model = CVE
    elif not spec or not batch:
        return {"status": "skipped", "entities": 0}
    else:
        model = spec["model"]

    if not batch:
        return {"status": "skipped", "entities": 0}

    guidance = _GAP_FIELD_GUIDANCE.get((entity_type, field))
    if not guidance:
        return {"status": "skipped_unsupported", "entity_type": entity_type, "field": field}

    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            return {"status": "no_admin_user"}

        # Pre-load country reference data for FK resolution — cheap one-shot.
        country_index: list[dict] | None = None
        if entity_type == "threat_actor" and field == "country":
            from app.models.country import Country

            rows = (await db.execute(select(Country.id, Country.name, Country.aliases))).all()
            country_index = [{"id": r[0], "name": r[1], "aliases": list(r[2] or [])} for r in rows]

        vendor_index: list[dict] | None = None
        if entity_type == "product" and field == "vendor_id":
            rows = (await db.execute(select(Vendor.id, Vendor.name))).all()
            vendor_index = [{"id": r[0], "name": r[1], "aliases": []} for r in rows]

        # Build the entities_block string the AI sees.
        entities_block = "\n".join(f"- entity_id={item['id']}  name={json.dumps(item['name'])}" for item in batch)

        variables = {
            "entity_type": entity_type,
            "field": field,
            "field_guidance": guidance,
            "entities_block": entities_block,
        }

        # Synthetic target so the engine's dedup cache doesn't collide across batches.
        synthetic_target = uuid.uuid4()
        try:
            result = await run_task(
                db=db,
                user_id=system_user_id,
                task_name="entity_enrichment_research",
                variables=variables,
                target_type="enrichment_gap_batch",
                target_id=synthetic_target,
                force=True,
                caller=Caller.system(system_user_id),
            )
        except Exception as e:  # provider quota / transient
            from app.ai.providers.claude_code_provider import QuotaExhaustedError

            if isinstance(e, QuotaExhaustedError):
                return {
                    "status": "provider_paused",
                    "pause_until": e.pause_until.isoformat() if getattr(e, "pause_until", None) else None,
                }
            raise

        if not result:
            return {"status": "no_assignment"}

        decisions = result.get("decisions") or []
        valid_ids = {item["id"] for item in batch}
        filled = 0
        skipped_low_conf = 0
        skipped_unknown = 0
        skipped_already_set = 0
        skipped_invalid = 0

        for d in decisions:
            if not isinstance(d, dict):
                continue
            eid_str = str(d.get("entity_id") or "")
            if eid_str not in valid_ids:
                continue

            status = d.get("status")
            if status == "unknown":
                skipped_unknown += 1
                continue
            if status != "filled":
                skipped_invalid += 1
                continue

            confidence = (d.get("confidence") or "").lower()
            # Direct-write only on high confidence (per the design pick).
            # Medium / low get logged as suggestions in the AIResult row but
            # don't touch the entity column.
            if confidence != "high":
                skipped_low_conf += 1
                continue

            raw_value = (d.get("value") or "").strip()
            if not raw_value:
                skipped_invalid += 1
                continue

            try:
                eid = uuid.UUID(eid_str)
            except ValueError:
                skipped_invalid += 1
                continue

            entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
            if not entity:
                skipped_invalid += 1
                continue

            entity_name = getattr(entity, "name", None) or getattr(entity, "cve_id", None) or str(entity.id)

            # Field-specific writeback with idempotency guards (don't overwrite
            # existing human / prior enrichment values).
            updated = await _apply_ai_gap_value(
                entity,
                field,
                raw_value,
                country_index=country_index,
                vendor_index=vendor_index,
            )
            if updated:
                # Field-level provenance for the profile popover: what was
                # asserted, by which pass, with the reason the model gave.
                from app.services.claim_provenance import record_claim

                await record_claim(
                    db,
                    entity_type=entity_type,
                    entity_id=entity.id,
                    field=field,
                    value=raw_value,
                    source_kind="ai_assessment",
                    source_ref="entity_gap_fill",
                    quote=(d.get("reason") or "") or None,
                    confidence=confidence,
                )

                # Record provenance so we can audit later.
                from app.models.enrichment import EnrichmentResult

                db.add(
                    EnrichmentResult(
                        entity_type=entity_type,
                        entity_id=entity.id,
                        source_type="ai_research",
                        raw_response={"field": field, "decision": d},
                        parsed_data={
                            "field": field,
                            "value": raw_value,
                            "source_urls": d.get("source_urls") or [],
                            "confidence": confidence,
                            "reason": (d.get("reason") or "")[:500],
                        },
                        enriched_at=datetime.now(UTC),
                        expires_at=datetime.now(UTC) + timedelta(days=180),
                        status="success",
                    )
                )
                # Drop a row into the unified hygiene feed so the user can SEE
                # what the AI just did (subject, value, source URLs).
                db.add(
                    EntityMaintenanceLog(
                        entity_type=entity_type,
                        entity_id=entity.id,
                        action="ai_enrich_filled",
                        mode="apply",
                        before={"entity": {"id": str(entity.id), "name": entity_name}},
                        after={
                            "field": field,
                            "value": raw_value[:500],
                            "confidence": confidence,
                            "source_urls": (d.get("source_urls") or [])[:5],
                        },
                        reasoning=("AI: " + (d.get("reason") or f"filled {field} via web research"))[:500],
                        applied=True,
                    )
                )
                filled += 1
            else:
                skipped_already_set += 1

        # Log the AI-said-unknown decisions too — the user wants to know which
        # entities the model couldn't confidently fill so they can manually
        # research or accept that no good source exists.
        for d in decisions:
            if not isinstance(d, dict):
                continue
            if d.get("status") != "unknown":
                continue
            eid_str = str(d.get("entity_id") or "")
            if eid_str not in valid_ids:
                continue
            try:
                eid = uuid.UUID(eid_str)
            except ValueError:
                continue
            entity = (await db.execute(select(model).where(model.id == eid))).scalar_one_or_none()
            if not entity:
                continue
            entity_name = getattr(entity, "name", None) or getattr(entity, "cve_id", None) or str(entity.id)
            db.add(
                EntityMaintenanceLog(
                    entity_type=entity_type,
                    entity_id=entity.id,
                    action="ai_enrich_unknown",
                    mode="apply",
                    before={"entity": {"id": str(entity.id), "name": entity_name}},
                    after={
                        "field": field,
                        "reason": (d.get("reason") or "no reliable source")[:500],
                    },
                    reasoning=("AI: " + (d.get("reason") or "no reliable source found"))[:500],
                    applied=True,
                )
            )

        await db.commit()
        return {
            "status": "processed",
            "entity_type": entity_type,
            "field": field,
            "batch_size": len(batch),
            "filled": filled,
            "skipped_low_confidence": skipped_low_conf,
            "skipped_unknown": skipped_unknown,
            "skipped_already_set": skipped_already_set,
            "skipped_invalid": skipped_invalid,
        }


async def _apply_ai_gap_value(
    entity,
    field: str,
    raw_value: str,
    *,
    country_index: list[dict] | None,
    vendor_index: list[dict] | None,
) -> bool:
    """Write the AI-provided value into the right column. Returns False if the
    field is already set or the value couldn't be coerced (e.g., country name
    didn't match any row)."""

    if field == "description":
        if (getattr(entity, "description", None) or "").strip():
            return False
        entity.description = raw_value[:2000]
        return True

    if field == "mitre_id":
        if (getattr(entity, "mitre_id", None) or "").strip():
            return False
        # Accept G#### / S#### / numeric forms — strip anything else.
        cleaned = raw_value.strip().upper()
        if not (cleaned.startswith(("G", "S")) and cleaned[1:].isdigit()):
            return False
        entity.mitre_id = cleaned
        return True

    if field == "malware_type":
        if (getattr(entity, "malware_type", None) or "").strip():
            return False
        entity.malware_type = raw_value.strip().lower()[:50]
        return True

    if field == "motivation":
        if (getattr(entity, "motivation", None) or "").strip():
            return False
        entity.motivation = raw_value.strip().lower()[:100]
        return True

    if field == "country" and country_index is not None:
        if getattr(entity, "origin_country_id", None) is not None:
            return False
        cid = _resolve_fk_by_name(country_index, raw_value)
        if not cid:
            return False
        entity.origin_country_id = cid
        return True

    if field == "vendor_id" and vendor_index is not None:
        if getattr(entity, "vendor_id", None) is not None:
            return False
        cid = _resolve_fk_by_name(vendor_index, raw_value)
        if not cid:
            return False
        entity.vendor_id = cid
        return True

    if field == "cvss":
        if getattr(entity, "cvss_score", None) is not None:
            return False
        try:
            score = float(raw_value.strip())
        except (TypeError, ValueError):
            return False
        if not (0.0 <= score <= 10.0):
            return False
        entity.cvss_score = score
        return True

    return False


# ============================================================
# Duplicate (merge) review — one task, a few AI calls
# ============================================================


@celery_app.task(bind=True, max_retries=1, soft_time_limit=1800)
def review_duplicate_entities(self) -> dict:
    """Judge the most likely duplicate pairs in the catalogue and file Merge
    proposals for the ones the model calls the same thing. Runs on the ai
    queue; a handful of calls per run, paced by the batch settings. One run at
    a time: the daily job and the Review tab's button can coincide, and two
    runs would file the same pairs twice."""
    import redis as _redis

    from app.services.entity_merge_review import LOCK_KEY, LOCK_TTL_SECONDS

    r = _redis.from_url(settings.redis_url)
    if not r.set(LOCK_KEY, "1", nx=True, ex=LOCK_TTL_SECONDS):
        r.close()
        logger.info("review_duplicate_entities already running — skipping")
        return {"status": "locked"}
    start = time.monotonic()
    try:
        stats = run_async(_review_duplicate_entities_async())
        CELERY_TASKS_TOTAL.labels(task_name="review_duplicate_entities", status="success").inc()
        logger.info("review_duplicate_entities: %s", stats)
        return stats
    except Exception:
        CELERY_TASKS_TOTAL.labels(task_name="review_duplicate_entities", status="error").inc()
        logger.exception("review_duplicate_entities failed")
        raise
    finally:
        CELERY_TASK_DURATION_SECONDS.labels(task_name="review_duplicate_entities").observe(time.monotonic() - start)
        try:
            r.delete(LOCK_KEY)
            r.close()
        except Exception:
            pass


async def _review_duplicate_entities_async() -> dict:
    from app.services.entity_merge_review import (
        TASK_NAME as MERGE_REVIEW_TASK,
    )
    from app.services.entity_merge_review import (
        file_verdicts,
        find_merge_candidates,
        pairs_block,
    )

    async with worker_session() as db:
        from app.services.system_settings import _ensure_cache, invalidate_cache

        invalidate_cache()
        await _ensure_cache(db)

        batch_size = max(0, int(settings.get("merge_review_batch_size")))
        per_call = max(1, int(settings.get("merge_review_pairs_per_call")))
        min_similarity = float(settings.get("merge_review_min_similarity"))
        retry_days = max(1, int(settings.get("merge_review_retry_days")))
        min_confidence = str(settings.get("merge_review_min_confidence") or "medium")
        if batch_size == 0:
            return {"status": "disabled", "candidates": 0}

        system_user_id = await _resolve_system_user(db)
        if not system_user_id:
            return {"status": "no_admin_user"}

        candidates = await find_merge_candidates(
            db, limit=batch_size, min_similarity=min_similarity, retry_days=retry_days
        )
        if not candidates:
            return {"status": "ok", "candidates": 0, "proposed": 0, "distinct": 0, "unsure": 0, "calls": 0}

        totals = {"proposed": 0, "distinct": 0, "unsure": 0, "ignored": 0}
        calls = 0
        for i in range(0, len(candidates), per_call):
            chunk = candidates[i : i + per_call]
            variables = {"pairs_block": pairs_block(chunk), "pair_count": len(chunk)}
            batch_id = uuid.uuid4()
            try:
                result = await run_task(
                    db=db,
                    user_id=system_user_id,
                    task_name=MERGE_REVIEW_TASK,
                    variables=variables,
                    target_type="merge_review_batch",
                    target_id=batch_id,
                    force=True,
                    caller=Caller.system(system_user_id),
                )
            except Exception as e:  # provider quota / transient
                from app.ai.providers.claude_code_provider import QuotaExhaustedError

                if isinstance(e, QuotaExhaustedError):
                    await db.commit()
                    return {
                        "status": "provider_paused",
                        "candidates": len(candidates),
                        "calls": calls,
                        **totals,
                        "pause_until": e.pause_until.isoformat() if getattr(e, "pause_until", None) else None,
                    }
                raise
            calls += 1
            if not result:
                await db.commit()
                return {"status": "no_assignment", "candidates": len(candidates), "calls": calls, **totals}
            # run_task hands back only the parsed answer; the stored result row
            # is what the filed proposals point at (the row's "view the model
            # output" link, the Origin facet).
            from app.models.ai_result import AIResult

            ai_result_id = (
                await db.execute(
                    select(AIResult.id)
                    .where(AIResult.target_type == "merge_review_batch", AIResult.target_id == batch_id)
                    .order_by(AIResult.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            counts = await file_verdicts(
                db, chunk, result.get("decisions") or [], min_confidence=min_confidence, ai_result_id=ai_result_id
            )
            for k, v in counts.items():
                totals[k] += v
            await db.commit()

    return {"status": "ok", "candidates": len(candidates), "calls": calls, **totals}
