"""What a Review proposal changes, how a single row is applied, and the
progress record of a background Apply all.

The Review tab's queue, its filters and its Apply / Dismiss live in
``app.api.hygiene`` (``_review_index`` and the functions on it). This module
holds the pieces those share with the adjudicate stage and the bulk worker
(``app.workers.proposal_apply_tasks``):

* the Domain facet (``proposal_domain`` and the per-log action sets);
* ``apply_link_removal_row`` — a link-log removal proposal made real;
* ``settle_adjudication_outcome`` — what an adjudication apply that found
  nothing left to do means for its proposal;
* the progress record a background Apply all publishes to Redis for the
  console to poll.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import redis as sync_redis
from sqlalchemy import func, select
from sqlalchemy import update as sql_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.exceptions import AppError
from app.models.entity_link_validation_log import EntityLinkValidationLog
from app.models.entity_maintenance import EntityMaintenanceLog
from app.services.entry_adjudication import (
    ACTION_MERGE,
    ACTION_RECLASSIFY,
    ACTION_VETO,
    ADJUDICATION_PROPOSAL_ACTIONS,
)

# The Review tab's Domain facet: what a proposal would change if applied.
# Both logs feed one queue there, so the split is by effect, not by table.
# Observables are an entity type, so dropping one is an entities proposal.
DOMAINS = ("links", "entities", "relationships")
_MAINT_DOMAIN_ACTIONS: dict[str, frozenset[str]] = {
    "links": frozenset({"adjudication_unlink", "adjudication_held_link"}),
    "relationships": frozenset({"adjudication_edge_demote"}),
}
_LINK_LOG_LINK_ACTIONS = frozenset({"shadow_remove", "removed", "restored"})


def proposal_domain(source: str, action: str) -> str:
    """Which part of the graph a log row is about.

    Link-log rows are entry↔entity links, except the reclassify advisories,
    which are about the entity. Maintenance rows are about the entity unless
    the adjudicator's action names an edge (demote) or an entry link (unlink).
    """
    if source == "link_validator":
        return "links" if action in _LINK_LOG_LINK_ACTIONS else "entities"
    for domain, actions in _MAINT_DOMAIN_ACTIONS.items():
        if action in actions:
            return domain
    return "entities"


def maint_actions_for_domain(domain: str | None) -> frozenset[str] | None:
    """Maintenance-log actions in ``domain``; None means no restriction.
    'entities' is everything the other domains do not claim."""
    if not domain:
        return None
    if domain == "entities":
        claimed = frozenset().union(*_MAINT_DOMAIN_ACTIONS.values())
        return frozenset(a for a in ADJUDICATION_PROPOSAL_ACTIONS if a not in claimed) | frozenset(
            {
                "normalize_name",
                "alias_collision",
                "vendor_autolink",
                "ttp_malformed_id",
                "cve_malformed_id",
                "cve_withdrawn",
                "merge",
                "reclassify",
                "orphan_prune",
                "no_op",
                "update_description",
                "update_aliases",
                "ai_enrich_filled",
                "ai_enrich_unknown",
                "merge_review_distinct",
            }
        )
    return _MAINT_DOMAIN_ACTIONS.get(domain, frozenset())


def link_log_actions_for_domain(domain: str | None) -> frozenset[str] | None:
    """Link-log actions in ``domain``; None means no restriction."""
    if not domain:
        return None
    if domain == "links":
        return _LINK_LOG_LINK_ACTIONS
    if domain == "entities":
        return frozenset({"needs_reclassification"})
    return frozenset()


PROGRESS_TTL_SECONDS = 2 * 60 * 60
BATCH_SIZE = 50
MAX_ERRORS_KEPT = 25


def _progress_key(job_id: str) -> str:
    return f"intelfeed:hygiene:bulk_apply:{job_id}"


# ---------------------------------------------------------------------------
# Row appliers
# ---------------------------------------------------------------------------


async def apply_link_removal_row(db: AsyncSession, row: EntityLinkValidationLog) -> bool:
    """Promote one shadow_remove row into the junction deletion (+ `removed`
    audit row, which names the proposal and is what History shows). The
    proposal itself is deleted — left in place it stayed in the queue as if
    nothing had happened. Returns True when the junction was already gone."""
    from app.intelligence.link_validation_apply import ENTITY_TYPES

    if row.action != "shadow_remove":
        raise AppError(code="invalid", message=f"can only apply shadow_remove rows (got {row.action})", status_code=400)
    spec = ENTITY_TYPES.get(row.entity_type)
    if not spec:
        raise AppError(code="invalid", message=f"unsupported entity_type: {row.entity_type}", status_code=400)
    jmodel, emodel, fk_attr = spec
    junction = (
        await db.execute(
            select(jmodel).where(jmodel.entry_id == row.entry_id, getattr(jmodel, fk_attr) == row.entity_id)
        )
    ).scalar_one_or_none()
    if junction is None:
        db.add(
            EntityLinkValidationLog(
                entry_id=row.entry_id,
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                entity_name_snapshot=row.entity_name_snapshot,
                action="removed",
                reason="Promoted from proposal; junction was already absent.",
                ai_result_id=row.ai_result_id,
            )
        )
        await db.delete(row)
        await db.flush()
        return True
    db.add(
        EntityLinkValidationLog(
            entry_id=row.entry_id,
            entity_type=row.entity_type,
            entity_id=row.entity_id,
            entity_name_snapshot=row.entity_name_snapshot,
            action="removed",
            reason=f"Promoted from proposal {row.id}: " + (row.reason or "")[:400],
            original_source=junction.source,
            original_confidence=junction.confidence,
            original_matched_names=list(junction.matched_names or []),
            original_paragraph_indices=list(junction.paragraph_indices or []),
            original_extracted_at=junction.extracted_at,
            ai_result_id=row.ai_result_id,
        )
    )
    await db.delete(junction)
    await db.delete(row)
    await db.execute(
        sql_update(emodel)
        .where(emodel.id == row.entity_id)
        .values(article_count=func.greatest(emodel.article_count - 1, 0))
    )
    await db.flush()
    return False


async def trim_alias_row(db: AsyncSession, row: EntityMaintenanceLog) -> dict:
    """Apply one alias_collision proposal: trim the alias from the entity,
    unlink what only that alias matched, recount, and write the applied row.
    Idempotent: an entity or alias already gone marks the proposal applied
    with ``skipped``. Returns {applied, skipped, entity_id, removed_alias}."""
    from app.api.entity_merge import ENTITY_TYPE_REGISTRY
    from app.api.hygiene import CASCADE_SPECS

    bad_alias = (row.after or {}).get("bad_alias")
    spec = ENTITY_TYPE_REGISTRY.get(row.entity_type)
    if not bad_alias or not spec:
        raise AppError(code="invalid", message="proposal has no alias or an unsupported type", status_code=400)
    model = spec["model"]
    entity = (await db.execute(select(model).where(model.id == row.entity_id))).scalar_one_or_none()
    current = list(getattr(entity, "aliases", None) or [])
    new_aliases = [a for a in current if a != bad_alias]
    if entity is None or len(new_aliases) == len(current):
        row.applied = True
        db.add(row)
        await db.flush()
        return {"applied": True, "skipped": True, "entity_id": row.entity_id, "removed_alias": bad_alias}
    # Unlink what only that alias matched and recount, like an alias edit on the profile;
    # otherwise the wrong links (and the inflated count) outlive the alias.
    unlinked = 0
    cascade = CASCADE_SPECS.get(row.entity_type)
    if cascade is not None:
        from app.api.entity_profiles import _unlink_entries_for_removed_aliases

        junction = cascade["junction"]
        unlinked = await _unlink_entries_for_removed_aliases(
            db, current, new_aliases, junction, getattr(junction, cascade["junction_fk"]), entity.id, entity=entity
        )
    entity.aliases = new_aliases
    row.applied = True
    db.add(row)
    db.add(
        EntityMaintenanceLog(
            entity_type=row.entity_type,
            entity_id=entity.id,
            action="alias_collision",
            mode="apply",
            before={"entity": {"id": str(entity.id), "name": entity.name, "aliases": current}},
            after={
                "bad_alias": bad_alias,
                "kind": (row.after or {}).get("kind"),
                "aliases_after": new_aliases,
                "unlinked_entries": unlinked,
                "promoted_from": str(row.id),
            },
            reasoning=f"Promoted from alias_collision proposal {row.id}.",
            applied=True,
        )
    )
    await db.flush()
    return {"applied": True, "skipped": False, "entity_id": entity.id, "removed_alias": bad_alias}


# What an apply that changes nothing reports when its outcome is already
# reached: the link, edge or entity it acts on is gone, the article is
# already linked to the entity a held-link proposal names, a capture's value
# is on the never-capture list (or no longer valid), or an analyst rejected
# the edge. Such a proposal is resolved, not left pending.
MOOT_REASONS = frozenset(
    {"entry gone", "edge gone or analyst-rejected", "entity gone", "already linked", "value refused"}
)


def outcome_is_moot(row: EntityMaintenanceLog, outcome: dict) -> bool:
    """True when an adjudication apply found nothing left to do."""
    if outcome.get("applied") or outcome.get("reason") not in MOOT_REASONS:
        return False
    # A veto wants the entity gone; its article going does not get it there.
    return not (row.action == ACTION_VETO and outcome.get("reason") == "entry gone")


async def settle_adjudication_outcome(db: AsyncSession, row: EntityMaintenanceLog, outcome: dict) -> str:
    """After ``apply_adjudication_row``: delete a moot proposal, and close the
    other proposals of an entity the apply removed (veto, merge, reclassify).
    Returns 'applied', 'resolved' (moot, row deleted) or 'skipped'."""
    from app.services.proposal_dismissals import settle_gone_entity

    if not outcome.get("applied"):
        if outcome_is_moot(row, outcome):
            await db.delete(row)
            await db.flush()
            return "resolved"
        return "skipped"
    if row.action in (ACTION_VETO, ACTION_MERGE, ACTION_RECLASSIFY) and row.entity_id:
        after = row.after or {}
        successor = None
        if row.action == ACTION_MERGE and after.get("target_id"):
            try:
                successor = (after.get("target_type") or row.entity_type, uuid.UUID(str(after["target_id"])))
            except ValueError:
                successor = None
        await settle_gone_entity(db, row.entity_type, row.entity_id, successor=successor)
    return "applied"


# ---------------------------------------------------------------------------
# Progress (Redis)
# ---------------------------------------------------------------------------


def new_progress(job_id: str, *, scope: dict[str, Any], total: int) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "scope": scope,
        "status": "queued",  # queued | running | done | error
        "total": total,
        "processed": 0,
        "applied": 0,
        "skipped": 0,
        "errors": [],
        "error_count": 0,
        "started_at": datetime.now(UTC).isoformat(),
        "finished_at": None,
        "message": None,
    }


async def write_progress(progress: dict[str, Any]) -> None:
    from app.services.redis_client import get_redis

    r = await get_redis()
    await r.set(_progress_key(progress["job_id"]), json.dumps(progress), ex=PROGRESS_TTL_SECONDS)


async def read_progress(job_id: str) -> dict[str, Any] | None:
    from app.services.redis_client import get_redis

    r = await get_redis()
    raw = await r.get(_progress_key(job_id))
    return json.loads(raw) if raw else None


def write_progress_sync(progress: dict[str, Any]) -> None:
    """The worker's copy of ``write_progress`` (its Redis client is synchronous)."""
    r = sync_redis.from_url(settings.redis_url, decode_responses=True)
    try:
        r.set(_progress_key(progress["job_id"]), json.dumps(progress), ex=PROGRESS_TTL_SECONDS)
    finally:
        r.close()
